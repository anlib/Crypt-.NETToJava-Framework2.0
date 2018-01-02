namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The CRLReason enumeration.
     * <pre>
     * CRLReason ::= Enumerated {
     *  unspecified             (0),
     *  keyCompromise           (1),
     *  cACompromise            (2),
     *  affiliationChanged      (3),
     *  superseded              (4),
     *  cessationOfOperation    (5),
     *  certificateHold         (6),
     *  removeFromCRL           (8),
     *  privilegeWithdrawn      (9),
     *  aACompromise           (10)
     * }
     * </pre>
     */
    public class CrlReason
        : DerEnumerated
    {
        public const int Unspecified = 0;
        public const int KeyCompromise = 1;
        public const int CACompromise = 2;
        public const int AffiliationChanged = 3;
        public const int Superseded = 4;
        public const int CessationOfOperation  = 5;
        public const int CertificateHold = 6;
        public const int RemoveFromCrl = 8;
        public const int PrivilegeWithdrawn = 9;
        public const int AACompromise = 10;

		public CrlReason(
			int reason)
			: base(reason)
        {
        }

		public CrlReason(
			DerEnumerated reason)
			: base(reason.Value.IntValue)
        {
        }
    }
}
