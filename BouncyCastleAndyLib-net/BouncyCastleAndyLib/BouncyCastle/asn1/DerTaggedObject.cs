using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /**
     * DER TaggedObject - in ASN.1 notation this is any object proceeded by
     * a [n] where n is some number - these are assume to follow the construction
     * rules (as with sequences).
     */
    public class DerTaggedObject
        : Asn1TaggedObject
    {
        /**
         * @param tagNo the tag number for this object.
         * @param obj the tagged object.
         */
        public DerTaggedObject(
            int              tagNo,
            Asn1Encodable    obj)
             : base(tagNo, obj)
        {
        }

        /**
         * @param explicitly true if an explicitly tagged object.
         * @param tagNo the tag number for this object.
         * @param obj the tagged object.
         */
        public DerTaggedObject(
            bool            explicitly,
            int             tagNo,
            Asn1Encodable   obj)
             : base(explicitly, tagNo, obj)
        {
        }

        /**
         * create an implicitly tagged object that contains a zero
         * length sequence.
         */
        public DerTaggedObject(int tagNo) : base(false, tagNo, new DerSequence())
        {
        }

        internal override void Encode(
            DerOutputStream derOut)
        {
            if (!IsEmpty())
            {
				byte[] bytes = obj.GetDerEncoded();

                if (explicitly)
                {
                    derOut.WriteEncoded((int)(Asn1Tags.Constructed | Asn1Tags.Tagged) | tagNo, bytes);
                }
                else
                {
                    //
                    // need to mark constructed types...
                    //
                    if ((bytes[0] & (byte) Asn1Tags.Constructed) != 0)
                    {
                        bytes[0] = (byte)((int)(Asn1Tags.Constructed | Asn1Tags.Tagged) | tagNo);
                    }
                    else
                    {
                        bytes[0] = (byte)((int)(Asn1Tags.Tagged) | tagNo);
                    }

                    derOut.Write(bytes, 0, bytes.Length);
                }
            }
            else
            {
                derOut.WriteEncoded((int)(Asn1Tags.Constructed | Asn1Tags.Tagged) | tagNo, new byte[0]);
            }
        }
    }
}
