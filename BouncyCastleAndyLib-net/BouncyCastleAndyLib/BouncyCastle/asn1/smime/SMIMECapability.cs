using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.Smime
{
    public class SmimeCapability
        : Asn1Encodable
    {
        /**
         * general preferences
         */
        public static readonly DerObjectIdentifier PreferSignedData = PkcsObjectIdentifiers.PreferSignedData;
        public static readonly DerObjectIdentifier CannotDecryptAny = PkcsObjectIdentifiers.CannotDecryptAny;
        public static readonly DerObjectIdentifier SmimeCapabilitiesVersions = PkcsObjectIdentifiers.SmimeCapabilitiesVersions;

		/**
         * encryption algorithms preferences
         */
        public static readonly DerObjectIdentifier DesCbc = new DerObjectIdentifier("1.3.14.3.2.7");
        public static readonly DerObjectIdentifier DesEde3Cbc = PkcsObjectIdentifiers.DesEde3Cbc;
        public static readonly DerObjectIdentifier RC2Cbc = PkcsObjectIdentifiers.RC2Cbc;

		private DerObjectIdentifier capabilityID;
        private Asn1Encodable        parameters;

		public SmimeCapability(
            Asn1Sequence seq)
        {
            capabilityID = (DerObjectIdentifier) seq[0];

			if (seq.Count > 1)
            {
                parameters = (Asn1Object) seq[1];
            }
        }

		public SmimeCapability(
            DerObjectIdentifier	capabilityID,
            Asn1Encodable		parameters)
        {
            this.capabilityID = capabilityID;
            this.parameters = parameters;
        }

		public static SmimeCapability GetInstance(
            object obj)
        {
            if (obj == null || obj is SmimeCapability)
            {
                return (SmimeCapability) obj;
            }

			if (obj is Asn1Sequence)
            {
                return new SmimeCapability((Asn1Sequence) obj);
            }

			throw new ArgumentException("Invalid SmimeCapability");
        }

		public DerObjectIdentifier CapabilityID { get { return capabilityID; } }

		public Asn1Encodable Parameters { get { return parameters; } }

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * SMIMECapability ::= Sequence {
         *     capabilityID OBJECT IDENTIFIER,
         *     parameters ANY DEFINED BY capabilityID OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(capabilityID);

			if (parameters != null)
            {
                v.Add(parameters);
            }

			return new DerSequence(v);
        }
    }
}
