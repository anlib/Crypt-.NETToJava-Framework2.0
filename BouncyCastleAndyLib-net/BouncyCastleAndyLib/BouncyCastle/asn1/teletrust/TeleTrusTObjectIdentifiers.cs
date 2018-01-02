using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Asn1.TeleTrust
{
    public sealed class TeleTrusTObjectIdentifiers
    {
		private TeleTrusTObjectIdentifiers()
		{
		}

        public static readonly DerObjectIdentifier TeleTrusTAlgorithm = new DerObjectIdentifier("1.3.36.3");

        public static readonly DerObjectIdentifier RipeMD160 = new DerObjectIdentifier(TeleTrusTAlgorithm + ".2.1");
        public static readonly DerObjectIdentifier RipeMD128 = new DerObjectIdentifier(TeleTrusTAlgorithm + ".2.2");
        public static readonly DerObjectIdentifier RipeMD256 = new DerObjectIdentifier(TeleTrusTAlgorithm + ".2.3");

        public static readonly DerObjectIdentifier TeleTrusTRsaSignatureAlgorithm = new DerObjectIdentifier(TeleTrusTAlgorithm + ".3.1");

        public static readonly DerObjectIdentifier RsaSignatureWithRipeMD160 = new DerObjectIdentifier(TeleTrusTRsaSignatureAlgorithm + ".2");
        public static readonly DerObjectIdentifier RsaSignatureWithRipeMD128 = new DerObjectIdentifier(TeleTrusTRsaSignatureAlgorithm + ".3");
        public static readonly DerObjectIdentifier RsaSignatureWithRipeMD256 = new DerObjectIdentifier(TeleTrusTRsaSignatureAlgorithm + ".4");
    }
}
