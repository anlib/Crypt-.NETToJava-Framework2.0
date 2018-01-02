using System;

namespace Org.BouncyCastle.Asn1
{
    /**
     * A Ber Null object.
     */
    public class BerNull
        : DerNull
    {
		public static new readonly BerNull Instance = new BerNull();

		[Obsolete("Use static Instance object")]
		public BerNull()
        {
        }

		internal override void Encode(
            DerOutputStream  derOut)
        {
            if (derOut is Asn1OutputStream || derOut is BerOutputStream)
            {
                derOut.WriteByte((byte) Asn1Tags.Null);
            }
            else
            {
                base.Encode(derOut);
            }
        }
    }
}
