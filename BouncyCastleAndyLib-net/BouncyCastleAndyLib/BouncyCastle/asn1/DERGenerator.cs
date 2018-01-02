using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public abstract class DerGenerator
        : Asn1Generator
    {
        private bool _tagged = false;
        private bool _isExplicit;
        private int _tagNo;

		protected DerGenerator(
            Stream outStream)
            : base(outStream)
		{
        }

        protected DerGenerator(
            Stream outStream,
            int tagNo,
            bool isExplicit)
            : base(outStream)
        {
            _tagged = true;
            _isExplicit = isExplicit;
            _tagNo = tagNo;
        }

        private void WriteLength(
            Stream outStream,
            int length)
        {
            if (length > 127)
            {
                int size = 1;
                int val = length;

				while ((val >>= 8) != 0)
                {
                    size++;
                }

				outStream.WriteByte((byte)(size | 0x80));

				for (int i = (size - 1) * 8; i >= 0; i -= 8)
                {
                    outStream.WriteByte((byte)(length >> i));
                }
            }
            else
            {
                outStream.WriteByte((byte)length);
            }
        }

		internal void WriteDerEncoded(
            Stream outStream,
            int          tag,
            byte[]       bytes)
        {
            outStream.WriteByte((byte) tag);
            WriteLength(outStream, bytes.Length);
            outStream.Write(bytes, 0, bytes.Length);
        }

		internal void WriteDerEncoded(
            int       tag,
            byte[]    bytes)
        {
            if (_tagged)
            {
                int tagNum = _tagNo | Asn1Tags.Tagged;

                if (_isExplicit)
                {
                    int newTag = _tagNo | Asn1Tags.Constructed | Asn1Tags.Tagged;

                    MemoryStream bOut = new MemoryStream();

                    WriteDerEncoded(bOut, tag, bytes);

                    WriteDerEncoded(Out, newTag, bOut.ToArray());
                }
                else
                {
                    if ((tag & Asn1Tags.Constructed) != 0)
                    {
                        WriteDerEncoded(Out, tagNum | Asn1Tags.Constructed, bytes);
                    }
                    else
                    {
                        WriteDerEncoded(Out, tagNum, bytes);
                    }
                }
            }
            else
            {
                WriteDerEncoded(Out, tag, bytes);
            }
        }

		internal void WriteDerEncoded(
            Stream outStream,
            int          tag,
            Stream  inStream)
        {
            outStream.WriteByte((byte) tag);

            MemoryStream bOut = new MemoryStream();

            int b = 0;
            while ((b = inStream.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte) b);
            }

            byte[] bytes = bOut.ToArray();

            WriteLength(outStream, bytes.Length);
            outStream.Write(bytes, 0, bytes.Length);
        }
    }
}
