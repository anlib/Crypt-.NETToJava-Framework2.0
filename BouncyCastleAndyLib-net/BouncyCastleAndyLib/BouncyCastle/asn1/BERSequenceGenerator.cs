using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public class BerSequenceGenerator
        : BerGenerator
    {
        public BerSequenceGenerator(
            Stream outStream)
            : base(outStream)
        {
            WriteBerHeader(Asn1Tags.Constructed | Asn1Tags.Sequence);
        }

        public BerSequenceGenerator(
            Stream outStream,
            int tagNo,
            bool isExplicit)
            : base(outStream, tagNo, isExplicit)
        {
            WriteBerHeader(Asn1Tags.Constructed | Asn1Tags.Sequence);
        }

        public void AddObject(
            Asn1Object obj)
        {
            byte[] encoded = obj.GetEncoded();
            Out.Write(encoded, 0, encoded.Length);
        }

        public void Close()
        {
            WriteBerEnd();
        }
    }
}
