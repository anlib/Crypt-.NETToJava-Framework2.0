using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public class BerGenerator
        : Asn1Generator
    {
        private bool      _tagged = false;
        private bool      _isExplicit;
        private int          _tagNo;

        protected BerGenerator(
            Stream outStream)
            : base(outStream)
        {
        }

        public BerGenerator(
            Stream outStream,
            int tagNo,
            bool isExplicit)
            : base(outStream)
        {
            _tagged = true;
            _isExplicit = isExplicit;
            _tagNo = tagNo;
        }

        public override Stream GetRawOutputStream()
        {
            return Out;
        }

        private void WriteHdr(
            int tag)
        {
            Out.WriteByte((byte) tag);
            Out.WriteByte((byte) 0x80);
        }

        protected void WriteBerHeader(
            int tag)
        {
            int tagNum = _tagNo | Asn1Tags.Tagged;

            if (_tagged)
            {
                if (_isExplicit)
                {
                    WriteHdr(tagNum | Asn1Tags.Constructed);
                    WriteHdr(tag);
                }
                else
                {
                    if ((tag & Asn1Tags.Constructed) != 0)
                    {
                        WriteHdr(tagNum | Asn1Tags.Constructed);
                    }
                    else
                    {
                        WriteHdr(tagNum);
                    }
                }
            }
            else
            {
                WriteHdr(tag);
            }
        }

        protected void WriteBerBody(
            Stream contentStream)
        {
            int ch;

            while ((ch = contentStream.ReadByte()) >= 0)
            {
                Out.WriteByte((byte) ch);
            }
        }

        protected void WriteBerEnd()
        {
            Out.WriteByte((byte) 0x00);
            Out.WriteByte((byte) 0x00);

            if (_tagged && _isExplicit)  // write extra end for tag header
            {
                Out.WriteByte((byte) 0x00);
                Out.WriteByte((byte) 0x00);
            }
        }
    }
}
