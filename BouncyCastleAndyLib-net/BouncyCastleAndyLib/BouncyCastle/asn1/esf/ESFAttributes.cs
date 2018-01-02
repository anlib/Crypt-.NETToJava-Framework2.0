using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.Esf
{
    public abstract class EsfAttributes
    {
        public static readonly DerObjectIdentifier SigPolicyId = PkcsObjectIdentifiers.IdAASigPolicyID;
        public static readonly DerObjectIdentifier CommitmentType = PkcsObjectIdentifiers.IdAACommitmentType;
        public static readonly DerObjectIdentifier SignerLocation = PkcsObjectIdentifiers.IdAASignerLocation;
    }
}
