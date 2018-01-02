using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /**
     * Base class for an application specific object
     */
    public class DerApplicationSpecific
        : Asn1Object
    {
        private readonly int	tag;
        private readonly byte[]	octets;

		public DerApplicationSpecific(
            int		tag,
            byte[]	octets)
        {
            this.tag = tag;
            this.octets = octets;
        }

        public DerApplicationSpecific(
            int				tag,
            Asn1Encodable	obj)
        {
            this.tag = tag | Asn1Tags.Constructed;

			this.octets = obj.GetDerEncoded();
        }

		public bool IsConstructed()
        {
            return (tag & Asn1Tags.Constructed) != 0;
        }

		public byte[] GetContents()
        {
            return octets;
        }

		public int ApplicationTag
        {
            get { return tag; }
        }

		public Asn1Encodable GetObject()
        {
			return Asn1Object.FromByteArray(GetContents());
		}

		internal override void Encode(
			DerOutputStream derOut)
        {
            derOut.WriteEncoded(Asn1Tags.Application | tag, octets);
        }

		protected override bool Asn1Equals(
			Asn1Object obj)
        {
			DerApplicationSpecific other = obj as DerApplicationSpecific;

			if (other == null)
				return false;

			return this.tag == other.tag
				&& Arrays.AreEqual(this.octets, other.octets);
        }

		protected override int Asn1GetHashCode()
		{
            byte[] b = this.GetContents();
            int hc = 0;

			for (int i = 0; i != b.Length; i++)
            {
                hc ^= ((int) b[i]) << (i % 4);
            }

			return hc ^ this.ApplicationTag;
        }
    }
}
